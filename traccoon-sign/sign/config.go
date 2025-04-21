package sign

// PARAMETERS
const (
	DimK            = 8
	DimEll          = 9
	B               = 70939015634276.8
	Bsquare         = "5032343939160168088238817280" // B^2
	Kappa           = 23
	LogN            = 8
	SigmaE          = 16384
	BoundE          = SigmaE * 15
	SigmaStar       = 2147483648
	BoundStar       = SigmaStar * 15
	KeySize         = 32              // 256 bits
	Q               = 562949953417729 // 49-bit NTT-friendly prime
	QNu             = 4095
	QXi             = 262143
	TrustedDealerID = 0
	CombinerID      = 1
	Xi              = 31
	Nu              = 37
)
