/dts-v1/;

/ {
	#address-cells = <0x1>;
	#size-cells = <0x0>;

	fsi0: kernelfsi@0 {
		#address-cells = <0x2>;
		#size-cells = <0x1>;
		compatible = "ibm,kernel-fsi";
		reg = <0x0 0x0 0x0>;

		index = <0x0>;
		status = "mustexist";

		pib@1000 {
			#address-cells = <0x2>;
			#size-cells = <0x1>;
			reg = <0x0 0x1000 0x7>;
			index = <0x0>;
			compatible = "ibm,fsi-pib", "ibm,power9-fsi-pib";
			include(p9-pib.dts.m4)dnl
		};

		i2cm@1800 {
			#address-cells = <0x1>;
			#size-cells = <0x0>;
			reg = <0x0 0x1800 0x400>;
			compatible = "ibm,fsi-i2c-master";
			include(p9-i2c.dts.m4)dnl
		};

		hmfsi@100000 {
			#address-cells = <0x2>;
			#size-cells = <0x1>;
			compatible = "ibm,fsi-hmfsi";
			reg = <0x0 0x100000 0x8000>;
			port = <0x1>;
			index = <0x1>;

			pib@1000 {
				#address-cells = <0x2>;
				#size-cells = <0x1>;
				 reg = <0x0 0x1000 0x7>;
				 index = <0x1>;
				 compatible = "ibm,fsi-pib", "ibm,power9-fsi-pib";
				 include(p9-pib.dts.m4)dnl
			};
		};
	};
};
