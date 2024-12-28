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
 * Sampler.cpp
 *
 *  Created on: 02.08.2011
 */

#include "Sampler.h"

Sampler::Sampler(float s) {
	int k;
	int num = 2 * ceil(2*s) + 1;

	/* Set all constant values for efficient sampling */
	k = ceil((float)num/s);
	this->constLeft = (float)k;
	this->constRight = (float)num/s;
	this->constPowS2 = (float)pow(s,2.0);
	this->constX1 = (num);
	this->constX2 = (num/2 + 1.0);
}

Sampler::~Sampler() {

}

ZZ_p Sampler::sampleD(){

	int x = 0;
	float u = 0;

	do {
		/* Choosing a number */
		x = ceil(((float)rand()/(float)RAND_MAX) * this->constX1) - this->constX2;	// x=[-s,s]
		/* Choosing the possibility */
		u = (float)rand()/(float)RAND_MAX;
	} while ((float)u * this->constLeft > this->constRight * exp((-PI*x*x)/this->constPowS2));

	return to_ZZ_p(x);

}

vec_ZZ_p Sampler::sampleGaussVec(int n){

	int i = 0;
	vec_ZZ_p res = vec_ZZ_p(INIT_SIZE, n);

	for(i = 0; i < n; i++){
		res[i] = this->sampleD();
	}

	return res;
}

mat_ZZ_p Sampler::sampleGaussMat(int n, int m){

	int i = 0;
	mat_ZZ_p res = mat_ZZ_p(INIT_SIZE,n,m);

	for(i = 0; i < n; i++){
		res[i] = this->sampleGaussVec(m);
	}

	return res;
}

mat_ZZ_p Sampler::sampleUniMat(int n, int m){

	int i = 0, j = 0;

	mat_ZZ_p res = mat_ZZ_p(INIT_SIZE, n, m);

	for (i = 0; i < n; i++){
		for (j = 0; j < m; j++){
			res[i][j] = random_ZZ_p();
		}
	}

	return res;
}
