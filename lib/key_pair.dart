class KeyPair {
  final String publicKey;
  final String privateKey;

  const KeyPair({required this.publicKey, required this.privateKey});

  @override
  String toString() {
    return 'KeyPair{publicKey: $publicKey, privateKey: $privateKey}';
  }
}
