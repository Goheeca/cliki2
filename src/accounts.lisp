(in-package #:cliki2)
(in-readtable cliki2)

(defstruct (account (:type list))
  name
  email
  password-salt
  password-digest
  (admin nil         :type (member nil :administrator :moderator)))

(defun account-link (account-name)
  #?[<a class="internal" href="${ #/site/account?name={account-name} }">${ account-name }</a>])

;;; passwords

(let ((kdf (ironclad:make-kdf 'ironclad:pbkdf2 :digest 'ironclad:sha256)))
  (defun password-digest (password salt)
    (ironclad:byte-array-to-hex-string
     (ironclad:derive-key
      kdf
      (flexi-streams:string-to-octets password :external-format :utf-8)
      (flexi-streams:string-to-octets salt     :external-format :utf-8)
      1000 128)
     :element-type 'character)))

(let ((AN "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"))
  (defun make-random-string (length)
    (map-into (make-string length) (lambda () (aref AN (random 62))))))

;;; registration

(defun maybe-show-form-error (error expected-error message)
  (when (equal error expected-error)
    #H[<div class="error-info">${ message }</div>]))

(defpage /site/register "Register" (name email error)
  (if (or *account* (youre-banned?))
      (redirect #/)
      (progn
#H[
<div>
  <h3>Create account</h3>
  <form id="registration" class="prefs" method="post" action="$(#/site/do-register)">
  <dl>]
  (maybe-show-form-error error "name" "Name required")
  (maybe-show-form-error error "nametaken"
                         "An account with this name already exists")
    #H[<dt><label for="name">Name:</label></dt>
    <dd><input class="regin" name="name" size="30" value="${(if name name "")}" /></dd>]
    (maybe-show-form-error error "email" "Invalid email address")
    #H[<dt><label for="email">Email:</label></dt>
    <dd><input class="regin" name="email" size="30" value="${(if email email "")}" /></dd>]
    (maybe-show-form-error error "password" "Password too short")
    #H[<dt><label for="password">Password:</label></dt>
       <dd><input class="regin" name="password" type="password" size="30" /></dd>]

    (maybe-show-form-error error "captcha" "Wrong captcha answer")
    (let ((captcha (make-captcha)))
      #H[<dt><label for="captcha">${captcha} is:</label></dt><dd>]
      (emit-captcha-inputs captcha "regin" 30)
      #H[</dd>])

    #H[<dt /><dd><input type="submit" value="Create account" /></dd>
  </dl>
  </form>
</div>])))

(defun password? (pw)
  (and pw (not (< (length pw) 8))))

(defun email-address? (str)
  (and str (not (string= str ""))))

(defun new-account (name email password)
  (let* ((salt     (make-random-string 50))
         (account  (make-account
                    :name            name
                    :email           email
                    :password-salt   salt
                    :password-digest (password-digest password salt))))
    (wiki-new 'account account)))

(defhandler /site/do-register (name email password)
  (let ((name (if name (escape-for-html name) "")))
    (acond
      ((youre-banned?) #/)
      ((cond ((or (not name) (string= name "")) "name")
             ((find-account name)               "nametaken")
             ((not (email-address? email))      "email")
             ((not (password? password))        "password")
             ((not (check-captcha))             "captcha"))
       #/site/register?name={name}&email={email}&error={it})
      (t (login (new-account (cut-whitespace name) email password))
         #/))))

;;; password recovery

(defun reset-password (account)
  (let ((salt     (make-random-string 50))
        (password (make-random-string 14)))
    (update-account account
                    account-password-digest (password-digest password salt)
                    account-password-salt   salt)
    (cl-smtp:send-email "localhost"
                        (password-reminder-email-address *wiki*)
                        (account-email account)
      #?"Your new ${ (wiki-name *wiki*) } wiki password"
#?"Someone (hopefully you) requested a password reset for a lost password on the ${ (wiki-name *wiki*) } wiki.
Your new password is: ${ password }")))

(defpage /site/reset-ok "Password reset successfully" ()
  #H[Password reset successfully. Check your inbox.])

;;; login

(defun check-password (password account)
  (and password (not (equal "" password))
       (equal (account-password-digest  account)
              (password-digest password (account-password-salt account)))))

(defhandler /site/login (name password reset-pw)
  (let ((account (find-account name)))
    (cond (*account*                          (referer))
          ((not account)                      #/site/cantfind?name={name})
          (reset-pw (reset-password account)  #/site/reset-ok)
          ((check-password password account)  (login account) (referer))
          (t                                  #/site/invalid-login))))

(defpage /site/invalid-login "Invalid Login" ()
  #H[Account name and/or password is incorrect])

(defpage /site/cantfind "Account does not exist" (name)
  #H[Account with name '${name}' doesn't exist])

(defpage /site/logout () ()
  (logout)
  (redirect #/))

;;; user page

(defun youre-banned? ()
  (or (and *account* (banned? (account-name *account*)))
      (banned? (real-remote-addr))))

(defpage /site/account #?"Account: ${name}" (name)
  (let ((account (find-account name))
        (edits   (edits-by-author name)))
    (if (or account edits)
        (progn
         #H[<h1>${name} account info page</h1>]
         (when *account*
           (flet ((ban (&key (un ""))
                    (when (and (not (youre-banned?)) (account-admin *account*))
                      #H[<form method="post" action="$(#/site/{un}ban?name={name})">
                           <input type="submit" value="${un}ban" />
                         </form>])))
             (cond
               ((equal name (account-name *account*))
                #H[<a href="$(#/site/preferences)">Edit preferences</a>])
               ((banned? name)
                #H[<em>banned user</em>] (ban :un "un"))
               (account
                (case (account-admin account)
                  (:administrator #H[<em>Administrator</em>])
                  (:moderator     #H[<em>Moderator</em>]
                                  (ban))
                  (t
                   (ban)
                   (when (account-admin *account*)
                     #H[<br />
                        <form method="post" action="$(#/site/make-moderator?name={name})">
                          <input type="submit" value="Make moderator" />
                        </form>]))))
               (t (ban)))))
         #H[<br />User page: ] (pprint-article-link name)
         #H[<br />Edits by ${name}: <ul>]
         (map nil #'render-revision-summary (edits-by-author name))
         #H[</ul>])
        (redirect #/site/cantfind?name={name}))))

;;; user preferences

(defpage /site/preferences-ok "Preferences updated" (what)
  #H[${what} updated successfully])

(defhandler /site/change-email (email password)
  (flet ((err (e) #/site/preferences?email={email}&error={e}))
    (cond ((not *account*)                          #/)
          ((not (email-address? email))             (err "email"))
          ((check-password password *account*)
           (update-account *account*
                           account-email email)     #/site/preferences-ok?what=Email)
          (t                                        (err "pw")))))

(defhandler /site/change-password (new-password confirm-password password)
  (flet ((err (e) #/site/preferences?error={e}))
    (cond ((not *account*)                          #/)
          ((not (password? new-password))             (err "npw"))
	  ((not (string= new-password confirm-password)) (err "cpw"))
          ((check-password password *account*)
           (let ((salt     (make-random-string 50)))
	     (update-account *account*
			     account-password-digest (password-digest new-password salt)
			     account-password-salt   salt))
	   #/site/preferences-ok?what=Password)
          (t                                        (err "opw")))))

(defpage /site/preferences "Account preferences" (email error)
  (if *account*
      (progn
	#H[<h3>Change account preferences</h3>
        <form id="changepassword" class="prefs" method="post"
              action="$(#/site/change-password)">
	<fieldset class="prefs">
	<legend>Password</legend>
        <dl>]
          (maybe-show-form-error error "npw" "Bad password")
          #H[<dt><label for="new-password">New password:</label></dt>
          <dd><input class="regin" type="password" name="new-password" title="new password" /></dd>]
	  (maybe-show-form-error error "cpw" "Different passwords")
          #H[<dt><label for="confirm-password">Confirm password:</label></dt>
          <dd><input class="regin" type="password" name="confirm-password" title="confirm password" /></dd>]
	  (maybe-show-form-error error "opw" "Wrong password")
          #H[<dt><label for="password">Old password:</label></dt>
          <dd><input class="regin" type="password" name="password" /></dd>
          <dt /><dd><input type="submit" value="change password" /></dd>
        </dl>
	</fieldset>
	</form>]

	#H[<form id="changemail" class="prefs" method="post"
              action="$(#/site/change-email)">
	<fieldset class="prefs">
	<legend>Email</legend>
        <dl>]
          (maybe-show-form-error error "email" "Bad email address")
          #H[<dt><label for="email">New email:</label></dt>
          <dd><input class="regin" type="text" name="email" title="new email"
                     value="${(if email email "")}" /></dd>]
          (maybe-show-form-error error "pw" "Wrong password")
          #H[<dt><label for="password">Enter password:</label></dt>
          <dd><input class="regin" type="password" name="password" /></dd>
          <dt /><dd><input type="submit" value="change email" /></dd>
        </dl>
	</fieldset>
	</form>])
      (redirect #/)))

;;; moderation

(defmacro moderator-handler (uri &body actions)
  `(defhandler ,uri ()
     (let ((name (cut-whitespace (get-parameter "name"))))
       (cond ((youre-banned?)                 #/)
             ((not (account-admin *account*)) (referer))
             (t ,@actions)))))

(moderator-handler /site/make-moderator
  (aif (find-account name)
       (progn (update-account it account-admin :moderator)
              (referer))
       #/site/cantfind?name={name}))

(moderator-handler /site/ban
  (unless (aand (find-account name) (eq (account-admin it) :administrator))
    (update-blacklist name t))
  (referer))

(moderator-handler /site/unban
  (update-blacklist name nil)
  (referer))
