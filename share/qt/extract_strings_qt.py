#!/usr/bin/python
'''
Extract _("...") strings for translation and convert to Qt4 stringdefs so that
they can be picked up by Qt linguist.
'''
from subprocess import Popen, PIPE
import glob
import operator

OUT_CPP="src/qt/bitcoinstrings.cpp"
EMPTY=['""']

def parse_po(text):
    """
    Parse 'po' format