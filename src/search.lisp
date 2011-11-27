(in-package #:cliki2)
(in-readtable cliki2)

(defclass concordance-entry (store-object)
  ((word     :initarg       :word
             :index-type    string-unique-index
             :index-reader  find-concordance-entry)
   (articles :initform      ()
             :accessor      articles
             :index-type    hash-list-index
             :index-reader  concordance-entries-for))
  (:metaclass persistent-class))

(deftransaction add-to-entry (entry article)
  (pushnew article (articles entry)))

(deftransaction remove-from-entry (entry article)
  (setf (articles entry) (remove article (articles entry))))

(defun get-concordance-entry (word)
  (or (find-concordance-entry word)
      (make-instance 'concordance-entry :word word)))

(defun words (content)
  (mapcar (lambda (x) (stem:stem (string-downcase x)))
          (remove-if #'zerop (ppcre:split "(\\s|[^\\w])" content)
                     :key #'length)))

(defun index-article (article)
  (let ((new-entries (mapcar #'get-concordance-entry
                             (words (cached-content article))))
        (old-entries (concordance-entries-for article)))
    (dolist (entry (set-difference old-entries new-entries))
      (remove-from-entry entry article))
    (dolist (entry (set-difference new-entries old-entries))
      (add-to-entry entry article))))

(defun search-articles (phrase)
  (let ((words (words phrase)))
    (sort (copy-list
           (reduce #'intersection
                   (mapcar (lambda (word)
                             (awhen (find-concordance-entry word)
                               (articles it)))
                           words)))
          #'< :key (lambda (article)
                     (loop for word in words
                           for weight from 0 by 100
                           thereis (awhen (search word (canonical-title article))
                                     (+ weight it))
                           finally (return most-positive-fixnum))))))

(defun paginate-article-summaries (start articles &optional (next-page-uri "?"))
  (let ((page-size 10)
        (start (or (parse-integer (or start "0") :junk-allowed t) 0)))
    #H[<ol start="${(1+ start)}">]
    (loop for i from start below (min (+ start page-size) (length articles))
       do (pprint-article-summary-li (elt articles i) "<br />"))
    #H[</ol>
    <div id="paginator">
    <span>Result page:</span>
    <ul>]
    (dotimes (p (ceiling (length articles) page-size))
      #H[<li>]
      (if (= start (* p page-size))
          #H[${(1+ p)}]
          #H[<a href="${next-page-uri}&start=${(* p page-size)}">${(1+ p)}</a></li>]))
    #H[</ul></div>]))

(defpage /site/search "Search results" (query start)
  #H[<h1>Search results</h1>]
  (aif (search-articles query)
       (paginate-article-summaries start it #U?query={query})
       #H[No results found]))
