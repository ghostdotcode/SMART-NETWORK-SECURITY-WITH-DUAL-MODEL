import pickletools
pfile = 'best_cybersecurity_model.pkl'
try:
    with open(pfile, 'rb') as f:
        data = f.read()
    # Disassemble; this may be long, filter for GLOBAL opcode lines
    out = pickletools.dis(data)
except Exception as e:
    print('ERROR:', e)
