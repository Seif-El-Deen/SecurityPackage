using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int publicA = enhanced_power(alpha, xa, q);
            // publicA = publicA % q;

            int publicB = enhanced_power(alpha, xb, q);
            //     publicB = publicB % q;

            int secretA = enhanced_power(publicB, xa, q);
            //     secretA = secretA % q;

            int secretB = enhanced_power(publicA, xb, q);
            //   secretB = secretB % q;



            List<int> result = new List<int>();
            result.Add(secretA);
            result.Add(secretB);

            return result;


        }
        public int enhanced_power(int basse , int power, int modulus) 
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * basse) % modulus;
            }
            return result;
        }
       
    }
}


