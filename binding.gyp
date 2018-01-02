{
  'variables': {
    'node_shared_openssl%': 'true'
  },
  'targets': [
    {
      'target_name': 'ed25519',
      'sources': [
        'src/ed25519/keypair.c',
        'src/ed25519/sign.c',
        'src/ed25519/open.c',
        'src/ed25519/crypto_verify_32.c',
        'src/ed25519/ge.c',
        'src/ed25519/fe.c',
        'src/ed25519/sc.c',
        'src/ed25519.cc'
      ],
      'conditions': [
        ['node_shared_openssl=="false"', {
          # so when "node_shared_openssl" is "false", then OpenSSL has been
          # bundled into the node executable. So we need to include the same
          # header files that were used when building node.
          'include_dirs': [
            '<(node_root_dir)/deps/openssl/openssl/include'
          ],
          "conditions" : [
            ["target_arch=='ia32'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/piii" ]
            }],
            ["target_arch=='x64'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/k8" ]
            }],
            ["target_arch=='arm'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/arm" ]
            }]
          ]
        }],
		# https://github.com/TooTallNate/node-gyp/wiki/Linking-to-OpenSSL
		['OS=="win"', {
		  'conditions': [
			# "openssl_root" is the directory on Windows of the OpenSSL files.
			# Check the "target_arch" variable to set good default values for
			# both 64-bit and 32-bit builds of the module.
			['target_arch=="x64"', {
			  'variables': {
				'openssl_root%': 'C:/OpenSSL-Win64'
			  },
			}, {
			  'variables': {
				'openssl_root%': 'C:/OpenSSL-Win32'
			  },
			}],
		  ],
	#	  'libraries': [ 
	#		'-l<(openssl_root)/lib/libcrypto.lib',
	#	  ],
		  'include_dirs': [
			'<(openssl_root)/include',
		  ],
		}]
      ],
      'include_dirs': [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
