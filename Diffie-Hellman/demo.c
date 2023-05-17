/*
 * This is a demo of the Diffie-Hellman key exchange algorithm implemented with
 * a 3072-bit prime number, 256-bit keys, and 24 as the generator.
 * */

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
  // Initialize variables
  mpz_t p, g, a, b, A, B, sa, sb;
  gmp_randstate_t state;
  unsigned long seed;

  // Initialize random number generator
  seed = time(NULL);
  gmp_randinit_default(state);
  gmp_randseed_ui(state, seed);

  // Set p and g
  mpz_init_set_str(
      p,
      "342846847796028973280265085652161751349528636208151801438169900597147458"
      "442108506818996131557658677841272464306496707369599429188452875941740672"
      "855955218105968207555267224630742885545832232048503447482131227903802133"
      "523637917856042504420579846243114922594443735873666425355253389686614991"
      "874284439213557769948038555572818035612956258273968302816494865728277145"
      "398256667916068727989876608654409943978772122842531537277108824957490144"
      "078636994131637719271069467810423857687598740066804258653122143344804539"
      "146138269053419927210633013641250468835805924185720051694566487791803872"
      "472756410079965965582037919822222846754512608960830169812310364194770940"
      "897964975528080433226145525701480223384729815019293798612468603550267957"
      "414046707346991151378467427338012680097344546839158800573557788958845765"
      "326093415745650974597857437239705250441710428651746710810250403618364216"
      "4320153026291949077955376842550678281045873806423251558923413",
      10);                       // 3072-bit prime number
  mpz_init_set_str(g, "24", 10); // 24 as the generator

  // Generate random secret keys
  mpz_init(a);
  mpz_urandomb(a, state, 256); // 256-bit secret key for Alice
  mpz_init(b);
  mpz_urandomb(b, state, 256); // 256-bit secret key for Bob

  // Calculate public keys
  mpz_init(A);
  mpz_powm(A, g, a, p); // Public key for Alice
  mpz_init(B);
  mpz_powm(B, g, b, p); // Public key for Bob

  // Calculate shared secret
  mpz_init(sa);
  mpz_powm(sa, B, a, p); // Shared secret for Alice
  mpz_init(sb);
  mpz_powm(sb, A, b, p); // Shared secret for Bob (same as Alice)

  // Output results
  gmp_printf("p = %Zd\n", p);
  gmp_printf("g = %Zd\n", g);
  gmp_printf("a = %Zd\n", a);
  gmp_printf("b = %Zd\n", b);
  gmp_printf("A = %Zd\n", A);
  gmp_printf("B = %Zd\n", B);
  gmp_printf("sa = %Zd\n", sa);
  gmp_printf("sb = %Zd\n", sb);

  printf("sa == sb: %d\n", mpz_cmp(sa, sb) == 0 ? 1 : 0);

  // Clean up
  mpz_clear(p);
  mpz_clear(g);
  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(A);
  mpz_clear(B);
  mpz_clear(sa);
  mpz_clear(sb);
  gmp_randclear(state);

  return 0;
}
