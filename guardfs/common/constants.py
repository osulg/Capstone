# common/constants.py
# 프로그램 전체에서 의미가 고정된 상수

STATE_LOW = "LOW"
STATE_SUSPICIOUS = "SUSPICIOUS"
STATE_MEDIUM = "MEDIUM"
STATE_HIGH = "HIGH"

OP_LOOKUP = "lookup"
OP_OPEN = "open"
OP_OPENDIR = "opendir"
OP_READ = "read"
OP_WRITE = "write"
OP_CREATE = "create"
OP_MKDIR = "mkdir"
OP_RENAME = "rename"
OP_RMDIR = "rmdir"
OP_UNLINK = "unlink"
OP_RELEASE = "release"
OP_TRUNCATE = "truncate"
OP_FTRUNCATE = "ftruncate"

TARGET_OPS = {
    OP_CREATE,
    OP_MKDIR,
    OP_RENAME,
    OP_RMDIR,
    OP_UNLINK,
    OP_WRITE,
}
