using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        DiffieHellman.DiffieHellman df = new DiffieHellman.DiffieHellman();
        AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            //int Qn = (p - 1) * (q - 1);
            int x = df.enhanced_power(M, e, n);
            return x;
           // throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int d = extendedEuclid.GetMultiplicativeInverse(e, Qn);
            int x = df.enhanced_power(C, d, n);
            return x;
            //throw new NotImplementedException();
        }
    }
}
