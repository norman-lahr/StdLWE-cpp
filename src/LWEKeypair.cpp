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
 * LWEKeypair.cpp
 *
 *  Created on: 28.07.2011
 */

#include "LWEKeypair.h"

LWEKeypair::LWEKeypair(Parameters *parameters){

	mat_ZZ_p R1, R2;
	mat_ZZ_p A, P;

	/* Initialize Sampler */
	Sampler *sampler = new Sampler(parameters->getS());

	/* Determine new pair of keys */
	R1 = sampler->sampleGaussMat(parameters->getN(), parameters->getL());
	R2 = sampler->sampleGaussMat(parameters->getN(), parameters->getL());
	A = sampler->sampleUniMat(parameters->getN(), parameters->getN());

	P = mat_ZZ_p(INIT_SIZE, parameters->getN(), parameters->getN());
	P = R1 - A * R2;

	this->publicKey = new LWEPublicKey(A, P);
	this->privateKey = new LWEPrivateKey(R2);

	/* Free memory */
	delete sampler;
	sampler = NULL;
}

LWEKeypair::LWEKeypair(LWEPublicKey *publicKey, LWEPrivateKey *privateKey) {

	this->publicKey = publicKey;
	this->privateKey = privateKey;
}

LWEKeypair::~LWEKeypair() {

	delete this->publicKey;
	delete this->privateKey;
	this->publicKey = NULL;
	this->privateKey = NULL;
}

LWEPublicKey* LWEKeypair::getPublicKey(){
	return this->publicKey;
}

LWEPrivateKey* LWEKeypair::getPrivateKey(){
	return this->privateKey;
}
