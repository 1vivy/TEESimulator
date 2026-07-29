package org.matrix.teesimulator.nativebridge;

@VintfStability
interface IRemoteOperationControl {
  oneway void release(in long lease);
}
