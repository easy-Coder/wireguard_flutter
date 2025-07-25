import 'package:flutter/services.dart';

import 'key_pair.dart';
import 'wireguard_flutter_platform_interface.dart';

class WireGuardFlutterMethodChannel extends WireGuardFlutterInterface {
  static const _methodChannelVpnControl =
      "billion.group.wireguard_flutter/wgcontrol";
  static const _methodChannel = MethodChannel(_methodChannelVpnControl);
  static const _eventChannelVpnStage =
      'billion.group.wireguard_flutter/wgstage';
  static const _eventChannel = EventChannel(_eventChannelVpnStage);

  @override
  Stream<VpnStage> get vpnStageSnapshot =>
      _eventChannel.receiveBroadcastStream().map(
            (event) => event == VpnStage.denied.code
                ? VpnStage.disconnected
                : VpnStage.values.firstWhere(
                    (stage) => stage.code == event,
                    orElse: () => VpnStage.noConnection,
                  ),
          );

  @override
  Future<void> initialize({required String interfaceName}) {
    return _methodChannel.invokeMethod("initialize", {
      "localizedDescription": interfaceName,
      "win32ServiceName": interfaceName,
    });
  }

  @override
  Future<void> startVpn({
    required String serverAddress,
    required String wgQuickConfig,
    required String providerBundleIdentifier,
  }) async {
    return _methodChannel.invokeMethod("start", {
      "serverAddress": serverAddress,
      "wgQuickConfig": wgQuickConfig,
      "providerBundleIdentifier": providerBundleIdentifier,
    });
  }

  @override
  Future<void> stopVpn() => _methodChannel.invokeMethod('stop');

  @override
  Future<void> refreshStage() => _methodChannel.invokeMethod("refresh");

  @override
  Future<VpnStage> stage() => _methodChannel.invokeMethod("stage").then(
        (value) => value != null
            ? VpnStage.values.firstWhere(
                (stage) => stage.code == value.toString(),
                orElse: () => VpnStage.disconnected,
              )
            : VpnStage.disconnected,
      );

  @override
  Future<KeyPair> generateKeyPair() async {
    final result = await _methodChannel
            .invokeMapMethod<String, String>('generateKeyPair') ??
        <String, String>{};
    if (!result.containsKey('publicKey') || !result.containsKey('privateKey')) {
      throw StateError('Could not generate keypair');
    }
    return KeyPair(
        publicKey: result['publicKey']!, privateKey: result['privateKey']!);
  }

  @override
  Future<int> getDownloadData() async {
    return await _methodChannel.invokeMethod<int>("getDownloadData") ?? 0;
  }

  @override
  Future<int> getUploadData() async {
    return await _methodChannel.invokeMethod<int>("getUploadData") ?? 0;
  }
}
