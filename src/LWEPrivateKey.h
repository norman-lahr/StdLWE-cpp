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
 * LWEPrivateKey.h
 *
 *  Created on: 28.07.2011
 */

#ifndef LWEPRIVATEKEY_H_
#define LWEPRIVATEKEY_H_

/* NTL library for big integers */
#include <NTL/mat_ZZ.h>

NTL_CLIENT

/**
 * Class for a LWE private key. This class stores
 * a private key of the LWE cryptosystem.
 */
class LWEPrivateKey {
public:
	/**
	 * Constructs empty LWEPrivateKey object.
	 */
	LWEPrivateKey(void);

	/**
	 * Constructs LWEPrivateKey object with given R2 matrix.
	 * \param R2 Secret matrix, chosen from an error distribution.
	 */
	LWEPrivateKey(mat_ZZ_p R2);

	virtual ~LWEPrivateKey();

	/**
	 * Getter for R2 matrix.
	 * \return Pointer to secret matrix r2
	 */
	mat_ZZ_p* getR2();

	/**
	 * Setter for R2 matrix.
	 * \param R2 Secret matrix
	 */
	void setR2(mat_ZZ_p R2);

private:
	mat_ZZ_p R2; /*!< Secret matrix */
};

/* Global operators */

/**
 * Reads private key from stream.
 * \param stream Input stream
 * \param key Pointer to a LWEPrivateKey object
 * \return Updated stream
 */
istream& operator>>(istream& stream, LWEPrivateKey* key);

/**
 * Writes private key to stream.
 * \param stream Output stream
 * \param key Pointer to a LWEPrivateKey object
 * \return Updated stream
 */
ostream& operator<<(ostream& stream, LWEPrivateKey& key);

#endif /* LWEPRIVATEKEY_H_ */
