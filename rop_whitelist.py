
from pyew_core import CPyew
import sys
import hashlib
pyew = CPyew(batch=True)
pyew.codeanalysis = True
pyew.deepcodeanalysis = True

path = sys.argv[1]
print path
d = open(path, 'rb').read()
md5 = hashlib.md5(d).hexdigest()
whitelist = set()
pyew.loadFile(path)
print 'loaded', len(pyew.functions), 'function'
for offset, function in pyew.functions.iteritems():
    whitelist.add(offset)
    for basic_block in function.basic_blocks:
        for instruction in basic_block.instructions:
            if instruction.mnemonic == 'CALL':
                whitelist.add(int(instruction.offset + instruction.size))


f = open(md5, 'w')
f.write(path + '\n')
for offset in sorted(whitelist):
    f.write('%d - %x\n' % (offset, offset))
f.close()
