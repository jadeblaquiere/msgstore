#!/usr/bin/env python
# 
# Copyright (c) 2016, Joseph deBlaquiere
# All rights reserved
#

def _lbr_reverse(left, right):
    x = { 'left': [], 'both': [], 'right': []}
    l = sorted(left, reverse=True)
    r = sorted(right, reverse=True)
    il = 0
    ir = 0
    while il < len(l) or ir < len(r):
        while il < len(l) and ((ir >= len(r)) or (l[il] > r[ir])):
            x['left'].append(l[il])
            il += 1
        while il >= len(l) and ir < len(r):
            x['right'].append(r[ir])
            ir += 1
        while il < len(l) and ir < len(r) and l[il] == r[ir]:
            x['both'].append(l[il])
            il += 1
            ir += 1
        while ir < len(r) and il < len(l) and r[ir] > l[il]:
            x['right'].append(r[ir])
            ir += 1
        while ir >= len(r) and il < len(l):
            x['left'].append(l[il])
            il += 1
    return x

def lbr(left, right, reverse=False):
    if reverse:
        return _lbr_reverse(left, right)
    x = { 'left': [], 'both': [], 'right': []}
    l = sorted(left)
    r = sorted(right)
    il = 0
    ir = 0
    while il < len(l) or ir < len(r):
        while il < len(l) and (ir >=len(r) or (l[il] < r[ir])):
            x['left'].append(l[il])
            il += 1
        while il >= len(l) and ir < len(r):
            x['right'].append(r[ir])
            ir += 1
        while il < len(l) and ir < len(r) and l[il] == r[ir]:
            x['both'].append(l[il])
            il += 1
            ir += 1
        while ir < len(r) and il < len(l) and r[ir] < l[il]:
            x['right'].append(r[ir])
            ir += 1
        while ir >= len(r) and il < len(l):
            x['left'].append(l[il])
            il += 1
    return x

