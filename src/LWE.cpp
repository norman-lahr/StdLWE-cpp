/*
 * LWE-Matrix -- Learning-With-Errors-based Encryption System --
 * Copyright (C) 2011 Norman Lahr

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Contact: norman@lahr.email

 * Refer to the file LICENSE for the details of the GPL.
 *
 * LWE.cpp
 *
 *  Created on: 28.07.2011
 */

#include "LWE.h"
#include <stdio.h>

LWE::LWE(Parameters *parameters) {

	this->parameters = parameters;
}

LWE::~LWE() {

}

void LWE::encrypt(LWEPublicKey *key){

	char *plaintext;
	unsigned long int length = 0;

	/* Read plaintext file */
	plaintext = this->readFile(parameters->getINamePlaintext(), &length);

	/* Determine the length of the last plaintext block
	 * for accurate plaintext reconstruction */
	typeof(this->parameters->getL()) remLength = 0;

	if(parameters->getPlainLength()){
		remLength = length % (this->parameters->getL() >> 3);
	}
	else{
		remLength = (length + sizeof(typeof(this->parameters->getL()))) % (this->parameters->getL() >> 3);
	}

	/* Char array for storing the delta in the first plaintext block */
	char *firstBlock = new char[this->parameters->getL() >> 3];

	/* Calculate number of plaintext blocks */
	int blocks = 0;

	if(parameters->getPlainLength()){
		blocks = length / (this->parameters->getL() >> 3);
		if(length % (this->parameters->getL() >> 3) != 0)
			blocks++;
	}
	else{
		blocks = (length + sizeof(remLength)) / (this->parameters->getL() >> 3);
		if((length + sizeof(remLength)) % (this->parameters->getL() >> 3) != 0)
					blocks++;
	}

	/* Temporary polynomial for actual ciphertext block */
	mat_ZZ_p *block;

	int i = 0;

	/* Initialize Sampler */
	this->sampler = new Sampler(this->parameters->getS());

	/* Output Stream */
	ofstream oFileCiphertext;

	/* Open ciphertext-file */
	oFileCiphertext.open((this->parameters->getOutName() != NULL) ? this->parameters->getOutName() : this->parameters->getONameCiphertext(), ios::out);

	/* Detect errors */
	if (!oFileCiphertext){
		cout << "Could not create " << ((this->parameters->getOutName() != NULL) ? this->parameters->getOutName() : this->parameters->getONameCiphertext()) << endl;

		/* return with error */
		exit(-1);
	}

	if(parameters->getPlainLength()){
		oFileCiphertext << remLength;
		for(i = 0; i < blocks; i++){
			block = this->encryptBlock(key, &plaintext[i*(this->parameters->getL() >> 3)]);
			oFileCiphertext << (*block)[0];
		}
	}
	else{
		/* Transform to Byte representation */
		for(i = 0; i < sizeof(remLength); i++){
			firstBlock[i] = (remLength & (0xFF << (i << 3))) >> (i << 3);
		}

		/* Encrypt first Block */
		for(i = sizeof(remLength); i < (this->parameters->getL() >> 3); i++){
			firstBlock[i] = plaintext[i - sizeof(remLength)];
		}
		block = this->encryptBlock(key, firstBlock);
		oFileCiphertext << (*block)[0];

		/* Encrypt remaining blocks, last block takes some "random" bits from memory */
		plaintext = plaintext + (this->parameters->getL() >> 3) - sizeof(remLength); // Set pointer of plaintext to the next block
		for(i = 1; i < blocks; i++){
			block = this->encryptBlock(key, &plaintext[(i-1)*(this->parameters->getL() >> 3)]);
			oFileCiphertext << (*block)[0];
		}
	}

	/* Close ciphertext-file */
	oFileCiphertext.close();

	/* Free memory */
	delete sampler;
	sampler = 0;
}

void LWE::decrypt(LWEPrivateKey *key){

	int length;

	/* Indicates end of file */
	bool endOfFile = false;

	/* Allocate memory for the resulting character array */
	char *block = new char[this->parameters->getL() >> 3];

	/* Temporary ciphertext */
	mat_ZZ_p *ciphertext = new mat_ZZ_p(INIT_SIZE, 1, this->parameters->getN() + this->parameters->getL());

	/* Length of last plaintext block */
	typeof(this->parameters->getL()) remLength = 0;

	/* File streams */
	ifstream iFileCiphertext;
	ofstream oFilePlaintext;

	/* Open ciphertext */
	iFileCiphertext.open(this->parameters->getINameCiphertext(), ios::in);

	/* Detect errors */
	if (!iFileCiphertext){
		cout << this->parameters->getINameCiphertext() << " not found!" << endl;

		/* return with error */
		exit(-1);
	}

	/* Get length of file */
	iFileCiphertext.seekg (0, ios::end);
	length = iFileCiphertext.tellg();
	iFileCiphertext.seekg (0, ios::beg);

	/* Open plaintext-file */
	oFilePlaintext.open((parameters->getOutName() != NULL) ? parameters->getOutName() : parameters->getONamePlaintext(), ios::binary);

	/* Detect errors */
	if (!oFilePlaintext){
		cout << "Could not create " << ((parameters->getOutName() != NULL) ? parameters->getOutName() : parameters->getONamePlaintext()) << endl;

		/* return with error */
		exit(-1);
	}

	if(parameters->getPlainLength()){
		iFileCiphertext >> remLength;
		endOfFile = iFileCiphertext.tellg() == length;
	}
	else{
		/* Read first ciphertext block */
		iFileCiphertext >> (*ciphertext)[0];
		endOfFile = iFileCiphertext.tellg() == length;

		/* Decrypt first block to determine the length of the last block */
		block = this->decryptBlock(key, ciphertext);
		remLength = (typeof(remLength)) *((typeof(remLength)*) block);

		/* Write first plaintext block to file */
		oFilePlaintext.write(block + sizeof(remLength), (!endOfFile || remLength == 0) ? (this->parameters->getL() >> 3) - sizeof(remLength) : remLength - sizeof(remLength));
	}

	/* Decrypt until end of file is reached */
	while(!endOfFile){
		/* Read ciphertext block */
		iFileCiphertext >> (*ciphertext)[0];
		endOfFile = iFileCiphertext.tellg() >= length;
		/* Decrypt block */
		block = this->decryptBlock(key, ciphertext);

		oFilePlaintext.write(block, ((!endOfFile || remLength == 0) ? (this->parameters->getL() >> 3) : remLength));
	}

	/* Close plaintext-file */
	oFilePlaintext.close();
}

mat_ZZ_p* LWE::encryptBlock(LWEPublicKey *key, char *plaintext){

	mat_ZZ_p e1T, e2T, e3T, mEncT, c1T, c2T;
	static mat_ZZ_p *res;
	vec_ZZ_p resTemp;

	res = new mat_ZZ_p(INIT_SIZE, 1, this->parameters->getL() + this->parameters->getN());

	/* Determine errors */
	e1T = this->sampler->sampleGaussMat(1, this->parameters->getN());
	e2T = this->sampler->sampleGaussMat(1, this->parameters->getN());
	e3T = this->sampler->sampleGaussMat(1, this->parameters->getL());

	/* Encode plaintext to matrix representation */
	mEncT = *this->encode(plaintext);

	/* Calculate the two ciphertext parts */
	c1T = mat_ZZ_p(INIT_SIZE, 1, this->parameters->getN());
	c2T = mat_ZZ_p(INIT_SIZE, 1, this->parameters->getL());

	c1T = e1T * (*key->getA()) + e2T * NTL::ident_mat_ZZ_p(this->parameters->getN());
	c2T = e1T * (*key->getP()) + (e3T + mEncT) * NTL::ident_mat_ZZ_p(this->parameters->getL());

	resTemp = c1T[0];
	/* Merge the two parts to a single ciphertext */
	NTL::append(resTemp, c2T[0]);

	(*res)[0] = resTemp;

	return res;
}

char* LWE::decryptBlock(LWEPrivateKey *key, mat_ZZ_p *ciphertext){

	mat_ZZ_p mEncT, c1T, c2T;

	c1T = mat_ZZ_p(INIT_SIZE, 1, this->parameters->getN());
	c2T = mat_ZZ_p(INIT_SIZE, 1, this->parameters->getL());

	this->split(&c1T, &c2T, ciphertext);

	/* Calculate the plaintext containing errors */
	mEncT = c1T * (*key->getR2()) + c2T * NTL::ident_mat_ZZ_p(this->parameters->getL());

	return this->decode(&mEncT);
}

mat_ZZ_p* LWE::encode(char* msg){

	int i = 0, qEnc = floor((float)this->parameters->getQ()/2.0);
	mat_ZZ_p *res = new mat_ZZ_p(INIT_SIZE, 1, this->parameters->getL());

	/* Encode l bits */
	for(i = 0; i < this->parameters->getL(); i++){
		(*res)[0][i] = (msg[(int)(i >> 3)] & (1 << (i%8))) ? qEnc : 0;
	}

	return res;
}

char* LWE::decode(mat_ZZ_p *msg){

	int i = 0;
	int qEnc = (int)floor((float)this->parameters->getQ()/4.0);
	static char *res = new char[this->parameters->getL()];

	/* Decode l bits */
	for(i = 0; i < this->parameters->getL(); i++){
		if(i < (this->parameters->getL() >> 3)) res[i] = 0;
		res[(int)(i >> 3)] |= (((NTL::rep((*msg)[0][i]) >= (this->parameters->getQ() - qEnc)) || (NTL::rep((*msg)[0][i]) < qEnc)) ? 0 : 1) << (i%8);
	}

	return res;
}

void LWE::split(mat_ZZ_p *c1T, mat_ZZ_p *c2T, mat_ZZ_p *cT){

	int i;

	for(i = 0; i < this->parameters->getN(); i++){
		(*c1T)[0][i] = (*cT)[0][i];
	}

	for(i = 0; i < this->parameters->getL(); i++){
		(*c2T)[0][i] = (*cT)[0][i + this->parameters->getN()];
	}
}

char* LWE::readFile(char *name, unsigned long int *length){

	ifstream iFile;

	iFile.open (name, ios::binary );

	/* Detect errors */
	if (!iFile){
		cout << name << " not found!" << endl;

		/* return with error */
		exit(-1);
	}

	/* Get length of file */
	iFile.seekg (0, ios::end);
	(*length) = iFile.tellg();
	iFile.seekg (0, ios::beg);

	/* Allocate memory */
	char *buffer = new char[(*length)];

	/* Read data as one block */
	iFile.read (buffer,(*length));
	iFile.close();

	return buffer;
}
