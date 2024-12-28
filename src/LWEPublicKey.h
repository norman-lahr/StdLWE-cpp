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
 * LWEPublicKey.h
 *
 *  Created on: 28.07.2011
 */

#ifndef LWEPUBLICKEY_H_
#define LWEPUBLICKEY_H_

/* NTL library for big integers */
#include <NTL/mat_ZZ_p.h>

NTL_CLIENT

/**
 * Class for a LWE public key. This class stores
 * a public key of the LWE cryptosystem.
 */
class LWEPublicKey {
public:
	/**
	 * Constructs empty LWEPublicKey object.
	 */
	LWEPublicKey(void);

	/**
	 * Constructs LWEPublicKey object with given matrices A and P.
	 * \param A Uniform random matrix
	 * \param P Per user public matrix
	 */
	LWEPublicKey(mat_ZZ_p A, mat_ZZ_p P);

	virtual ~LWEPublicKey();

	/**
	 * Getter for matrix A.
	 * \return Pointer to matrix A
	 */
	mat_ZZ_p* getA();

	/**
	 * Getter for matrix P.
	 * \return Pointer to matrix P
	 */
	mat_ZZ_p* getP();

	/**
	 * Setter for matrix A.
	 * \param a Uniform random matrix A
	 */
	void setA(mat_ZZ_p A);

	/**
	 * Setter for matrix P.
	 * \param p Per user public matrix P
	 */
	void setP(mat_ZZ_p P);

private:
	mat_ZZ_p A, /*!< Uniform random matrix */
			P;	/*!< Per user public matrix */

};

/* Global operators */

/**
 * Reads public key from stream.
 * \param stream Input stream
 * \param key Pointer to a LWEPublicKey object
 * \return Updated stream
 */
istream& operator>>(istream& stream, LWEPublicKey *key);

/**
 * Writes public key to stream.
 * \param stream Output stream
 * \param key Pointer to a LWEPublicKey object
 * \return Updated stream
 */
ostream& operator<<(ostream& stream, LWEPublicKey& key);

#endif /* LWEPUBLICKEY_H_ */
