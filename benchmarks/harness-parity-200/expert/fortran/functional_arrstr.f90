! SPDX-License-Identifier: Apache-2.0

module functional_arrstr_expert
  use iso_c_binding
  use functional, only: arrstr
  implicit none
contains
  subroutine fuzz_arrstr(data, count) bind(C)
    type(c_ptr), value :: data
    integer(c_size_t), value :: count
    character(kind=c_char), pointer :: input(:)
    character(len=:), allocatable :: output
    call c_f_pointer(data, input, [int(count)])
    output = arrstr(input)
  end subroutine fuzz_arrstr
end module functional_arrstr_expert
