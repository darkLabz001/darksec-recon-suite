package dh

// Code generated from OpenSSL's explicit curve parameters.
// These curves are not part of the Go standard library, so the
// auditor carries the parameters it needs to validate SAE commit
// elements on them.

// curve holds a short Weierstrass curve y^2 = x^3 + ax + b over GF(p).
type curve struct {
	p, a, b, gx, gy, n string
}

var (
	// P192 (OpenSSL prime192v1).
	curveP192 = curve{
		p:  "00fffffffffffffffffffffffffffffffeffffffffffffffff",
		a:  "00fffffffffffffffffffffffffffffffefffffffffffffffc",
		b:  "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
		gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
		gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
		n:  "00ffffffffffffffffffffffff99def836146bc9b1b4d22831",
	}
	// P224 (OpenSSL secp224r1).
	curveP224 = curve{
		p:  "00ffffffffffffffffffffffffffffffff000000000000000000000001",
		a:  "00fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
		b:  "00b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
		gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
		gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
		n:  "00ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
	}
	// BrainpoolP224 (OpenSSL brainpoolP224r1).
	curveBrainpoolP224 = curve{
		p:  "00d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
		a:  "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
		b:  "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
		gx: "0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
		gy: "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
		n:  "00d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
	}
	// BrainpoolP256 (OpenSSL brainpoolP256r1).
	curveBrainpoolP256 = curve{
		p:  "00a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
		a:  "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
		b:  "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
		gx: "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
		gy: "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
		n:  "00a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
	}
	// BrainpoolP384 (OpenSSL brainpoolP384r1).
	curveBrainpoolP384 = curve{
		p:  "008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
		a:  "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
		b:  "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
		gx: "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
		gy: "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
		n:  "008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
	}
	// BrainpoolP512 (OpenSSL brainpoolP512r1).
	curveBrainpoolP512 = curve{
		p:  "00aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
		a:  "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
		b:  "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
		gx: "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
		gy: "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
		n:  "00aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
	}
)
