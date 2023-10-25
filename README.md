# crypto_pkg

Package containing symmetric and asymmetric key ciphers and attacks

## Ciphers 
<ul>
<li>Asymmetric Key (PKE)</li>
<ul>
<li>Textbook RSA</li>
<li>DGVH</li>
</ul>
<li>Symmetric key</li>
<ul>
<li>AES</li>
<li>Modified vulnerable version of AES - AES without shift rows</li>
</ul>
</ul>

## Attacks
The following attacks are on know plain text attacks.
<ul>
<li>Double encryption attack on AES</li>
<li>Key recovery on the modified version of AES</li>
</ul>

Usage examples are provided in the attacks source code files
<ul>
<li>attacks/block_ciphers/double_encryption.py</li>
<li>attacks/block_ciphers/modified_aes.py</li>
</ul>

## Usage
The <i>Textbook RSA</i> and the <i>DGVH</i> PKEs are used in the [BruteSniffing_Fisher](https://github.com/programmingAthlete/BruteSniffing_Fisher) repository.