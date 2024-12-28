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
 * LWEPrivateKey.cpp
 *
 *  Created on: 28.07.2011
 */

#include "LWEPrivateKey.h"

LWEPrivateKey::LWEPrivateKey(){

}

LWEPrivateKey::LWEPrivateKey(mat_ZZ_p R2) {

	this->R2 = R2;
}

LWEPrivateKey::~LWEPrivateKey() {

}

mat_ZZ_p* LWEPrivateKey::getR2(){
	return &this->R2;
}

void LWEPrivateKey::setR2(mat_ZZ_p R2){
	this->R2 = R2;
}

istream& operator>>(istream& stream, LWEPrivateKey* key){

	mat_ZZ_p R2 = mat_ZZ_p();

	stream >> R2;

	key->setR2(R2);

	return stream;
}

ostream& operator<<(ostream& stream, LWEPrivateKey& key){

	stream << *key.getR2();

	return stream;
}
