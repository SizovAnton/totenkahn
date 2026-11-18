import json

STATUS_CODES = {'passed': 0, 'completed': 0, 'passed_with_warnings': 0, 'blocked': 1, 'error': 2, 'failed': 2,
                'needs_verification': 3, 'needs_action': 3, 'interrupted': 130}

def status_code(status):
    return STATUS_CODES.get(status, 2)

def run_cli(entry):
    try:
        result = entry()
        
        if type(result) is int:
            return result
        
        if isinstance(result, dict) and 'status' in result:
            return status_code(result['status'])
        
        return 0
    
    except KeyboardInterrupt:
        print(json.dumps({'status': 'interrupted', 'reason': 'Operation interrupted; inspect retained journals and evidence'}), flush=True)
        
        return 130
    
    except Exception as exc:
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__,
                          'reason': str(exc)}, ensure_ascii=False), flush=True)
        
        return 2
