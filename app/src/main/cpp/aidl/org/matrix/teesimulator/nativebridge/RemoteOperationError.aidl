package org.matrix.teesimulator.nativebridge;

@VintfStability @Backing(type="int")
enum RemoteOperationError {
  NONE = 0,
  INVALID_LEASE = 1,
  INVALID_ARGUMENT = 2,
  INVALID_OPERATION = 3,
  REPLAY_CONFLICT = 4,
  DEADLINE_EXCEEDED = 5,
  CANCELLED = 6,
  ACCESS_DENIED = 7,
  PROTOCOL_FAILED = 8,
  REMOTE_UNAVAILABLE = 9,
  CONTROLLER_CLOSED = 10,
  INTERNAL_ERROR = 11,
}
