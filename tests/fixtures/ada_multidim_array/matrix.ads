--  SPDX-License-Identifier: Apache-2.0
--  A multi-dimensional (2-D) array parameter. The array decoder used to emit a
--  single-subscript fill loop (`Tmp (I)`) which fails to compile on an N-D array
--  ("too few subscripts in array reference"); it now nests a loop per dimension.
package Matrix is
   type Covariance_Matrix_Type is array (1 .. 3, 1 .. 3) of Float;
   procedure Consume (M : Covariance_Matrix_Type);
end Matrix;
