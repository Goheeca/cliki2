(in-package #:cliki2)
(in-readtable cliki2)

(defclass wiki-diff (diff:diff) ()
  (:default-initargs
   :window-class 'wiki-diff-window))

(defclass wiki-diff-window (diff:diff-window) ())

(defun choose-chunks (chunks a b c)
  (loop for chunk in chunks appending
       (let ((kind (diff:chunk-kind chunk))
             (lines (diff:chunk-lines chunk)))
         (cond ((or (eq kind :common) (eq kind a)) lines)
               ((eq kind b) (list (format nil "~{~&~A~}" lines)))
               ((eq kind c) (make-list (length lines)))))))

(defun compare-strings (original modified)
  (labels ((str2arr (str)
             (map 'simple-vector #'char-code str))
           (wrt (str out start end)
             (loop for i from start below end
                   for ch = (char str i) do
                   (if (char= ch #\Newline)
                       (write-line "<br />" out)
                       (write-char ch out))))
           (fmt (regions str offset-fun length-fun)
             (with-output-to-string (out)
               (loop for reg in regions
                     for modified-p = (typep reg 'diff:modified-diff-region)
                     for start = (funcall offset-fun reg)
                     for end = (+ start (funcall length-fun reg)) do
                     (progn (when modified-p (princ "<span>" out))
                            (wrt str out start end)
                            (when modified-p (princ "</span>" out)))))))
    (let ((rawdiff (diff:compute-raw-diff (str2arr original)
                                          (str2arr modified))))
      (values (fmt rawdiff original #'diff:original-start #'diff:original-length)
              (fmt rawdiff modified #'diff:modified-start #'diff:modified-length)))))

(defmethod diff:render-diff-window :before ((window wiki-diff-window) *html-stream*)
  #H[<tr>
  <td /><td class="diff-line-number">Line ${(diff:original-start-line window)}:</td>
  <td /><td class="diff-line-number">Line ${(diff:modified-start-line window)}:</td>
</tr>])

(defmethod diff:render-diff-window ((window wiki-diff-window) *html-stream*)
  (labels ((escape (x) (when x (escape-for-html x)))
           (td (line dash class)
             (if line
                 #H[<td class="diff-marker">${dash}</td><td class="${class}">${line}</td>]
                 #H[<td class="diff-marker" /><td />]))
           (diff-line (original modified)
             (td original "-" "diff-deleteline")
             (td modified "+" "diff-addline")))
    (loop for original in (choose-chunks (diff:window-chunks window) :delete :replace :create)
          for modified in (choose-chunks (diff:window-chunks window) :create :insert :delete) do
         (let ((original (escape original))
               (modified (escape modified)))
           #H[<tr>]
           (if (and original modified)
               (if (string= original modified)
                   #H[<td class="diff-marker" />
                      <td class="diff-context">${original}</td>
                      <td class="diff-marker" />
                      <td class="diff-context">${original}</td>]
                   (multiple-value-call #'diff-line
                     (compare-strings original modified)))
               (diff-line original modified))
           #H[</tr>]))))
