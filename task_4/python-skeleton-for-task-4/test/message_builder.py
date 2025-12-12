import constants as const

def mk_hello_msg():
    return {"type": "hello", "version": const.VERSION, "agent": const.AGENT}

def mk_getobject_msg(objid):
    return {"type":"getobject", "objectid":objid}

def mk_object_msg(obj_dict):
    return {"type":"object", "object":obj_dict}

def mk_chaintip_msg(blockid):
    return {"type": "chaintip", "blockid": blockid}

def mk_getchaintip_msg():
    return {"type": "getchaintip"}