package org.matrix.teesimulator.nativebridge;

@VintfStability @Backing(type="int")
enum RemoteOperationDisposition {
  FAILED = 0,
  APPLIED = 1,
  REPLAYED = 2,
}
