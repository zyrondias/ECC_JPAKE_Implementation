import 'dart:typed_data';

import 'package:ecc_jpake/SchnorrZKP.dart';
import 'package:pointycastle/ecc/curves/prime256v1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';
import 'JPAKEUtil.dart';

class ECCJPakeDemo {
  late ECCurve_prime256v1 ecc_curve;
  late BigInt a;
  late BigInt b;
  late BigInt cofactor;
  late BigInt n;
  late ECPoint G;
  BigInt q = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);

  String password = 'password';
  String aliceID = 'alice';
  String bobID = 'bob';

  ECCJPakeDemo() {
    ecc_curve = ECCurve_prime256v1();
    a = ecc_curve.curve.a!.toBigInteger()!;
    b = ecc_curve.curve.b!.toBigInteger()!;
    cofactor = ecc_curve.h!;
    n = ecc_curve.n;
    G = ecc_curve.G;
  }

  void run() {
    print('************ Curve Domain Params ***************');
    print('Curve Param a ${a.bitLength} bits : ' + a.toRadixString(16));
    print('Curve Param b ${b.bitLength} bits : ' + b.toRadixString(16));
    print('Curve Param co-factor ${cofactor.bitLength} bits : ' +
        cofactor.toRadixString(16));
    print(
        'Base point G ( ${G.getEncoded().length} bytes: ${(JPAKEUtil.decodeBigInt(G.getEncoded())).toRadixString(16)}');
    print(
        'X coordinate : ${G.x!.toBigInteger()!.bitLength} bits : ${G.x!.toBigInteger()!.toRadixString(16)}');
    print(
        'Y coordinate : ${G.y!.toBigInteger()!.bitLength} bits : ${G.y!.toBigInteger()!.toRadixString(16)}');

    print('Order of the base point n (${n.bitLength} bits): ' +
        n.toRadixString(16));

    final s = JPAKEUtil.calculateS(password);

    // Alice generates
    final x1 = JPAKEUtil.createRandomInRange(BigInt.one, n - BigInt.one);
    final x2 = JPAKEUtil.createRandomInRange(BigInt.one, n - BigInt.one);
    final x3 = JPAKEUtil.createRandomInRange(BigInt.one, n - BigInt.one);
    final x4 = JPAKEUtil.createRandomInRange(BigInt.one, n - BigInt.one);

    final X1 = G * x1;
    final zkpX1 = SchnorrZKP();
    zkpX1.generateZKP(G, n, x1, X1!, aliceID);

    final X2 = G * x2;
    final zkpX2 = SchnorrZKP();
    zkpX2.generateZKP(G, n, x2, X2!, aliceID);

    final X3 = G * x3;
    final zkpX3 = SchnorrZKP();
    zkpX3.generateZKP(G, n, x3, X3!, bobID);

    final X4 = G * x4;
    final zkpX4 = SchnorrZKP();
    zkpX4.generateZKP(G, n, x4, X4!, bobID);

    print('************Step 1**************\n');
    print('Alice sends to Bob: ');
    print(
        'G*x1= ${(JPAKEUtil.decodeBigInt(X1.getEncoded())).toRadixString(16)}');
    print(
        'G*x2= ${(JPAKEUtil.decodeBigInt(X2.getEncoded())).toRadixString(16)}');
    print(
        'KP{x1}: {V= ${JPAKEUtil.decodeBigInt(zkpX1.getV().getEncoded()).toRadixString(16)}; r= ${zkpX1.getr().toRadixString(16)})}');
    print(
        'KP{x2}: {V= ${JPAKEUtil.decodeBigInt(zkpX2.getV().getEncoded()).toRadixString(16)}; r= ${zkpX2.getr().toRadixString(16)})}');
    print('Bob sends to Alice: ');
    print(
        'G*x3= ${(JPAKEUtil.decodeBigInt(X3.getEncoded())).toRadixString(16)}');
    print(
        'G*x4= ${(JPAKEUtil.decodeBigInt(X4.getEncoded())).toRadixString(16)}');
    print(
        'KP{x3}: {V= ${JPAKEUtil.decodeBigInt(zkpX3.getV().getEncoded()).toRadixString(16)}; r= ${zkpX3.getr().toRadixString(16)})}');
    print(
        'KP{x2}: {V= ${JPAKEUtil.decodeBigInt(zkpX4.getV().getEncoded()).toRadixString(16)}; r= ${zkpX4.getr().toRadixString(16)})}');
    print('');

    if (aliceID == bobID) {
      throw Exception('Invalid ID');
    }

    if (verifyZKP(G, X3, zkpX3.getV(), zkpX3.getr(), bobID) &&
        verifyZKP(G, X4, zkpX4.getV(), zkpX4.getr(), bobID)) {
      print('Alice checks KP{x3} : OK');
      print('Alice checks KP{X4}: OK');
    }

    if (verifyZKP(G, X1, zkpX1.getV(), zkpX1.getr(), aliceID) &&
        verifyZKP(G, X2, zkpX2.getV(), zkpX2.getr(), aliceID)) {
      print('Bob checks KP{x1} : OK');
      print('Bob checks KP{X2}: OK');
    }

    final GA = (X1 + X3)! + X4;
    final A = GA! * ((x2 * s) % n);

    final ZKPX2s = SchnorrZKP();
    ZKPX2s.generateZKP(GA, n, (x2 * s) % n, A!, aliceID);

    final GB = (X1 + X2)! + X3;
    final B = GB! * ((x4 * s) % n);

    final ZKPX4s = SchnorrZKP();
    ZKPX4s.generateZKP(GB, n, (x4 * s) % n, B!, bobID);

    print('');
    print('***************************Step 2**********************');
    print('Alice sends to bob:');
    print('A = ${JPAKEUtil.decodeBigInt(A.getEncoded()).toRadixString(16)}');
    print(
        'KP{x2*s}: {V= ${JPAKEUtil.decodeBigInt(ZKPX2s.getV().getEncoded()).toRadixString(16)}');
    print('Bob sends to ALice:');
    print('B = ${JPAKEUtil.decodeBigInt(B.getEncoded()).toRadixString(16)}');
    print(
        'KP{x4*s}: {V= ${JPAKEUtil.decodeBigInt(ZKPX4s.getV().getEncoded()).toRadixString(16)}');

    if (verifyZKP(GB, B, ZKPX4s.getV(), ZKPX4s.getr(), bobID)) {
      print('Alice checks KP{x4*s}: OK');
    } else {
      print('error');
    }

    if (verifyZKP(GA, A, ZKPX2s.getV(), ZKPX2s.getr(), aliceID)) {
      print('Bob checks KP{x2*s}: OK');
    } else {
      print('error');
    }

    final Kax = ((B - (X4 * ((x2 * s) % n))!)! * x2)!.x;
    final Kbx = ((A - (X2 * ((x4 * s) % n))!)! * x4)!.x;

    final Ka = JPAKEUtil.getSHA256FromBigInt(Kax!.toBigInteger()!);
    final Kb = JPAKEUtil.getSHA256FromBigInt(Kbx!.toBigInteger()!);
    print('ALice computes session key : ${Ka.toRadixString(16)}');
    print('Bob computes session Key : ${Kb.toRadixString(16)} ');
  }

  bool verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInt r, String id) {
    final h = JPAKEUtil.getSha256(generator, V, X, id);
    if (X.isInfinity) {
      return false;
    }
    final x = X.x!.toBigInteger()!;
    final y = X.y!.toBigInteger()!;

    if (x.compareTo(BigInt.zero) <= -1 ||
        x.compareTo(q - BigInt.one) >= 1 ||
        y.compareTo(BigInt.zero) <= -1 ||
        y.compareTo(q - BigInt.one) >= 1) {
      return false;
    }
    try {
      ecc_curve.curve.decodePoint(X.getEncoded());
    } catch (E) {
      print(E);
    }

    if ((X * cofactor)!.isInfinity) {
      return false;
    }

    if (V == ((generator * r)! + (X * (h % n)))) {
      return true;
    }
    return false;
  }
}
