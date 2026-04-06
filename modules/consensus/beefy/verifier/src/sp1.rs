// Copyright (C) Polytope Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SP1 BEEFY proof verification

use crate::{error::Error, verify_parachain_headers};
use alloc::vec::Vec;
use alloy_sol_types::{SolValue, sol};
use beefy_verifier_primitives::{ConsensusState, ParachainHeader, Sp1BeefyProof};
use codec::Encode;
use ismp::messaging::Keccak256;

sol! {
	struct PublicInputs {
		bytes32 authorities_root;
		uint256 authorities_len;
		bytes32 leaf_hash;
		bytes32[] headers;
	}
}

/// Verify an SP1 BEEFY consensus proof and return the updated consensus state
/// and verified parachain headers.
///
/// 1. Check proof is not stale
/// 2. Match validator_set_id against known authority sets
/// 3. Build public inputs (authority root, len, leaf hash, header hashes)
/// 4. Verify SP1 proof
/// 5. Update authority sets if epoch changed
pub fn verify_sp1_consensus<H: Keccak256 + Send + Sync>(
	trusted_state: ConsensusState,
	sp1_proof: Sp1BeefyProof,
	vkey_hash: &str,
) -> Result<(Vec<u8>, Vec<ParachainHeader>), Error> {
	if trusted_state.latest_beefy_height >= sp1_proof.commitment.block_number {
		return Err(Error::StaleHeight {
			trusted_height: trusted_state.latest_beefy_height,
			current_height: sp1_proof.commitment.block_number,
		});
	}

	let authority = if sp1_proof.commitment.validator_set_id == trusted_state.next_authorities.id {
		&trusted_state.next_authorities
	} else if sp1_proof.commitment.validator_set_id == trusted_state.current_authorities.id {
		&trusted_state.current_authorities
	} else {
		return Err(Error::UnknownAuthoritySet { id: sp1_proof.commitment.validator_set_id });
	};

	let public_inputs =
		build_sp1_public_inputs::<H>(&sp1_proof, authority.keyset_commitment.into(), authority.len);

	sp1_verifier::PlonkVerifier::verify(
		&sp1_proof.proof,
		&public_inputs,
		vkey_hash,
		sp1_verifier::PLONK_VK_BYTES,
	)
	.map_err(|_| Error::Sp1VerificationFailed)?;

	let verified_headers =
		verify_parachain_headers::<H>(sp1_proof.mmr_leaf.extra, sp1_proof.parachain)?;

	let mut new_state = trusted_state;
	if sp1_proof.mmr_leaf.beefy_next_authority_set.id > new_state.next_authorities.id {
		new_state.current_authorities = new_state.next_authorities.clone();
		new_state.next_authorities = sp1_proof.mmr_leaf.beefy_next_authority_set;
	}
	new_state.latest_beefy_height = sp1_proof.commitment.block_number;

	Ok((new_state.encode(), verified_headers))
}

fn build_sp1_public_inputs<H: Keccak256>(
	proof: &Sp1BeefyProof,
	authority_root: [u8; 32],
	authority_len: u32,
) -> Vec<u8> {
	use alloy_sol_types::private::FixedBytes;

	let leaf_hash: [u8; 32] = H::keccak256(&proof.mmr_leaf.encode()).into();

	let headers: Vec<FixedBytes<32>> = proof
		.parachain
		.parachains
		.iter()
		.map(|h| FixedBytes::from(Into::<[u8; 32]>::into(H::keccak256(&h.header))))
		.collect();

	let inputs = PublicInputs {
		authorities_root: FixedBytes::from(authority_root),
		authorities_len: alloy_sol_types::private::U256::from(authority_len),
		leaf_hash: FixedBytes::from(leaf_hash),
		headers,
	};

	inputs.abi_encode()
}
