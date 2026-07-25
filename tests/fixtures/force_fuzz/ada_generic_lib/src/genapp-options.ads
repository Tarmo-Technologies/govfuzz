--  SPDX-License-Identifier: Apache-2.0
with Vendorgen.Opt;
package Genapp.Options is

   --  Two instantiations of the SAME missing generic with DIFFERENT type actuals.
   --  A stub that baked one instance's concrete type into the generic would break
   --  the other, so the model has to type the shared entity by the FORMAL.
   Parser : Vendorgen.Opt.Argument_Parser :=
     Vendorgen.Opt.Create_Parser (Help => "help text", Command_Name => "genapp");

   package Label is new Vendorgen.Opt.Parse_Option
     (Parser      => Parser,
      Short       => "-l",
      Long        => "--label",
      Arg_Type    => Genapp.Label_Name,
      Default_Val => Genapp.Empty_Label,
      Convert     => Genapp.To_Label);

   package Retries is new Vendorgen.Opt.Parse_Option
     (Parser      => Parser,
      Short       => "-r",
      Long        => "--retries",
      Arg_Type    => Natural,
      Default_Val => 0,
      Convert     => Genapp.To_Retries);

end Genapp.Options;
