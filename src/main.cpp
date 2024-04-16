#include <iostream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

using namespace libsnark;

int main() {
    // Initialize the protoboard with the correct field type
    protoboard<FieldT> pb;

    // Define your circuit and constraints
    pb_variable<FieldT> x;
    pb_variable<FieldT> y;
    pb_variable<FieldT> z;

    // Allocate variables to the protoboard
    x.allocate(pb);
    y.allocate(pb);
    z.allocate(pb);

    // Add constraints: x * y = z
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, y, z));

    // Set inputs
    pb.val(x) = 3;
    pb.val(y) = 5;

    // Generate keys
    keypair<FieldT> kp = generate_keypair<FieldT>();

    // Prove
    r1cs_ppzksnark_prover<FieldT> prover(pb);
    proof<FieldT> proof = prover.prove(kp.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify
    r1cs_ppzksnark_verifier_weak_IC<FieldT> verifier(pb);
    bool verified = verifier.verify(kp.vk, pb.primary_input(), proof);

    if (verified) {
        std::cout << "Proof is verified!" << std::endl;
    } else {
        std::cout << "Proof is not verified!" << std::endl;
    }

    return 0;
}
