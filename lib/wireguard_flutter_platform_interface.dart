import 'key_pair.dart';

abstract class WireGuardFlutterInterface {
  Stream<VpnStage> get vpnStageSnapshot;

  Future<void> initialize({required String interfaceName});

  Future<void> startVpn({
    required String serverAddress,
    required String wgQuickConfig,
    required String providerBundleIdentifier,
  });

  Future<void> stopVpn();

  Future<KeyPair> generateKeyPair();
  Future<void> refreshStage();
  Future<VpnStage> stage();
  Future<bool> isConnected() =>
      stage().then((stage) => stage == VpnStage.connected);

  Future<int> getUploadData();
  Future<int> getDownloadData();
}

enum VpnStage {
  connected('connected'),
  connecting('connecting'),
  disconnecting('disconnecting'),
  disconnected('disconnected'),
  waitingConnection('wait_connection'),
  authenticating('authenticating'),
  reconnect('reconnect'),
  noConnection('no_connection'),
  preparing('prepare'),
  denied('denied'),
  exiting('exiting');

  final String code;

  const VpnStage(this.code);
}
