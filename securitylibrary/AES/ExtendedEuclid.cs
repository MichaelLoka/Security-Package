using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int ModResult = (number % baseN); //105194
            if (ModResult < 1)
                ModResult += baseN;

            for (int i = 1; i < baseN; i++ )
            {
                // (BigInteger) multiply for large integers since final testcase has large input number
                var MultiplicationResult = Math.BigMul(ModResult, i);
                if ((MultiplicationResult % baseN) == 1)
                    return i;
            }
            return -1;
        }
    }
}
