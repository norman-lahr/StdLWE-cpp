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
 * LWEPublicKey.cpp
 *
 *  Created on: 28.07.2011
 */

#include "LWEPublicKey.h"

LWEPublicKey::LWEPublicKey(){

}

LWEPublicKey::LWEPublicKey(mat_ZZ_p A, mat_ZZ_p P) {

	this->A = A;
	this->P = P;
}

LWEPublicKey::~LWEPublicKey() {

}

mat_ZZ_p* LWEPublicKey::getA(){
	return &this->A;
}

mat_ZZ_p* LWEPublicKey::getP(){
	return &this->P;
}

void LWEPublicKey::setA(mat_ZZ_p A){
	this->A = A;
}

void LWEPublicKey::setP(mat_ZZ_p P){
	this->P = P;
}

istream& operator>>(istream& stream, LWEPublicKey* key){

	mat_ZZ_p A = mat_ZZ_p(),
			P = mat_ZZ_p();

	stream >> A;
	stream >> P;

	key->setA(A);
	key->setP(P);

	return stream;
}

ostream& operator<<(ostream& stream, LWEPublicKey& key){

	stream << *key.getA();
	stream << *key.getP();

	return stream;
}
