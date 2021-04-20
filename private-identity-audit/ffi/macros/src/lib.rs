//use convert_case::{Case, Casing};
use proc_macro::TokenStream;
//use proc_macro2::Ident;
use quote::quote;
//use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(ArrBuilder)]
pub fn derive(_input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    //let input = parse_macro_input!(input as DeriveInput);

    //let arr_name = &input.ident;
    //let arr_name_snake_case = Ident::new(
    //    &format!("empty_{}", arr_name.to_string().to_case(Case::Snake)),
    //    arr_name.span(),
    //);
    //let element_name = Ident::new(
    //    &format!("{}", &(arr_name.to_string())[3..]),
    //    arr_name.span(),
    //);

    //let gen_from_vec_method = quote! {
    //    pub fn new(mut vec: Vec<#element_name>) -> Self {
    //        Self {
    //            arr: vec.as_mut_ptr(),
    //            n: vec.len(),
    //            cap: vec.capacity(),
    //        }
    //    }
    //};

    //let gen_to_vec_method = quote! {
    //    unsafe fn to_vec(&self) -> Vec<#element_name> {
    //        Vec::from_raw_parts((*self).arr, (*self).n, (*self).cap)
    //    }
    //};

    //let gen_empty_struct_method = quote! {
    //    #[no_mangle]
    //    pub extern "C" fn #arr_name_snake_case() -> #arr_name {
    //        let mut vec: Vec<#element_name> = Vec::new();

    //        let output = #arr_name {
    //            arr: vec.as_mut_ptr(),
    //            n: vec.len(),
    //            cap: vec.capacity(),
    //        };
    //        // Do not deallocate
    //        std::mem::forget(vec);
    //        output
    //    }
    //};

    // Build the output, possibly using quasi-quotation
    let expanded = quote! {
        //impl #arr_name {
        //    #gen_from_vec_method

        //    #gen_to_vec_method

        //}

        #[no_mangle]
        pub extern "C" fn aaa() {
        }
        //#gen_empty_struct_method
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(expanded)
}
