(defparameter log-file-path "./logs/ufw.log")

(with-open-file (file-stream log-file-path)
    (do ((l (read-line file-stream) (read-line file-stream nil 'eof)))
        ((eq l 'eof) (return))
      (format t "~a~%" l)))
