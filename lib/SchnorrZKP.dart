import 'package:ecc_jpake/JPAKEUtil.dart';
import 'package:pointycastle/pointycastle.dart';

class SchnorrZKP {
  ECPoint? _V;
  BigInt? _r;

  SchnorrZKP();

  void generateZKP(
      ECPoint generator, BigInt n, BigInt x, ECPoint X, String userID) {
    final v = JPAKEUtil.createRandomInRange(BigInt.one, n - BigInt.one);
    _V = generator * v;
    final h = JPAKEUtil.getSha256(generator, _V!, X, userID);
    _r = (v - (x * h)) % n;
  }

  ECPoint getV() {
    return _V!;
  }

  BigInt getr() {
    return _r!;
  }
}
