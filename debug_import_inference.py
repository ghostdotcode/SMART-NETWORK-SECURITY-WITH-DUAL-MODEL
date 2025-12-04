import traceback
import importlib
import sys

importlib.invalidate_caches()

try:
    import inference
    print('\nImported inference module successfully')
    # show what objects are available
    print('Attributes in inference module:', [k for k in dir(inference) if not k.startswith('__')])
except Exception:
    traceback.print_exc()
    exc = sys.exc_info()[1]
    print('\nException type:', type(exc))
    print('Exception repr:', repr(exc))
