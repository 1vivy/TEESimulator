package org.matrix.teesimulator.nativebridge;

import org.matrix.teesimulator.nativebridge.RemoteOperationReply;

@SensitiveData @VintfStability
interface IRemoteOperationControl {
  oneway void release(in long lease);
  RemoteOperationReply update(in long lease, in long step, in byte[] input);
  RemoteOperationReply finish(in long lease, in long step, in @nullable byte[] input);
  RemoteOperationReply abort(in long lease, in long step);
}
