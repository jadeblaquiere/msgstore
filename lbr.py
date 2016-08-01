# Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ciphrtxt nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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

