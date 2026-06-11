package httpd

import (
	"net/http"
	"time"

	"github.com/elexation/dockwatch/internal/auth"
	"github.com/elexation/dockwatch/internal/store"
)

// requireSession admits only requests with a valid session cookie, redirecting
// the rest to the entry page; a valid session has its expiry slid forward.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.validSession(r)
		if !ok {
			s.clearSessionCookie(w)
			http.Redirect(w, r, s.entryPath(), http.StatusSeeOther)
			return
		}
		s.slide(w, sess)
		next(w, r)
	}
}

// entryPath is /setup while setup is still armed, else /login.
func (s *Server) entryPath() string {
	if s.adminExists() {
		return "/login"
	}
	return "/setup"
}

// validSession returns the live session for the request's cookie, evicting an expired one.
func (s *Server) validSession(r *http.Request) (store.Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return store.Session{}, false
	}
	sess, found, err := s.cfg.Store.GetSession(c.Value)
	if err != nil || !found {
		return store.Session{}, false
	}
	if !s.now().Before(sess.Expiry) {
		_ = s.cfg.Store.DeleteSession(sess.ID)
		return store.Session{}, false
	}
	return sess, true
}

// slide advances a session's expiry, but only after it drops a day below the
// ceiling, so steady browsing does not write to bbolt every request.
func (s *Server) slide(w http.ResponseWriter, sess store.Session) {
	now := s.now()
	if sess.Expiry.Sub(now) > s.ttl-24*time.Hour {
		return
	}
	sess.Expiry = now.Add(s.ttl)
	if err := s.cfg.Store.PutSession(sess); err == nil {
		s.setSessionCookie(w, sess.ID)
	}
}

// startSession creates and persists a new session for username and sets its cookie.
func (s *Server) startSession(w http.ResponseWriter, username string) error {
	id, err := auth.NewSessionID()
	if err != nil {
		return err
	}
	sess := store.Session{ID: id, Username: username, Expiry: s.now().Add(s.ttl)}
	if err := s.cfg.Store.PutSession(sess); err != nil {
		return err
	}
	s.setSessionCookie(w, id)
	return nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.ttl / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
