package org.matrix.teesimulator.nativebridge;

import org.matrix.teesimulator.nativebridge.RemoteOperationDisposition;
import org.matrix.teesimulator.nativebridge.RemoteOperationError;

@VintfStability
parcelable RemoteOperationReply {
  long step = -1;
  RemoteOperationDisposition disposition = RemoteOperationDisposition.FAILED;
  RemoteOperationError error = RemoteOperationError.INTERNAL_ERROR;
  boolean terminal = true;
  @nullable byte[] output;
}
