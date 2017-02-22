;;; rcli-mode.el --- Major mode for Robust Common Language Infrastructure disassembly files

;; Version: 0.1.0
;; Author: Vladimir Panteleev
;; Url: https://github.com/CyberShadow/rclidasm
;; Keywords: languages
;; Package-Requires: ((emacs "24.3"))

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; see the file COPYING.  If not, write to
;; the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.

;;; Commentary:

;; A Major Emacs mode for editing Robust Common Language
;; Infrastructure disassembly files.

;;; Code:

(require 'sdlang-mode)

(defvar rcli-mode-syntax-table nil "Syntax table for `rcli-mode'.")

(setq rcli-mode-syntax-table (copy-syntax-table sdlang-mode-syntax-table))

(define-derived-mode rcli-mode sdlang-mode "RCLI"
  "Major mode for Robust Common Language Infrastructure disassembly files."
  )

(add-to-list 'auto-mode-alist '("\\.rcli\\'" . rcli-mode))

(provide 'rcli-mode)
;;; rcli-mode.el ends here
