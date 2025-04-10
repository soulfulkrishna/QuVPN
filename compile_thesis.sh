#!/bin/bash

# Exit on error
set -e

echo "Installing TeX Live packages if needed..."
apt-get update
apt-get install -y texlive-latex-base texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended

echo "Compiling thesis document..."
pdflatex thesis_document.tex
pdflatex thesis_document.tex  # Run twice for proper references

echo "Compilation complete. PDF document ready: thesis_document.pdf"