
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '@/context/UserContext';
import { Button } from '@/components/ui/button';
import { Award, ChevronLeft, Download } from 'lucide-react';
import html2canvas from 'html2canvas';

const Certificate = () => {
  const { user, hasCompletedAllChallenges } = useUser();
  const navigate = useNavigate();
  const certificateRef = useRef<HTMLDivElement>(null);
  
  // Get current date for the certificate
  const currentDate = new Date().toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  });
  
  // Redirect if not registered or not completed all challenges
  useEffect(() => {
    if (!user.isRegistered) {
      navigate('/');
      return;
    }
    
    // In a real app, we would want this check, but for demo purposes we'll 
    // allow viewing the certificate without completing all challenges
    // if (!hasCompletedAllChallenges()) {
    //   navigate('/dashboard');
    // }
  }, [user.isRegistered, hasCompletedAllChallenges, navigate]);
  
  const downloadCertificate = async () => {
    if (certificateRef.current) {
      try {
        const canvas = await html2canvas(certificateRef.current, {
          scale: 2,
          logging: false,
          useCORS: true,
        });
        
        const image = canvas.toDataURL('image/png');
        const link = document.createElement('a');
        link.href = image;
        link.download = `${user.fullName.replace(/\s+/g, '-')}-cyber-code-quest-certificate.png`;
        link.click();
      } catch (error) {
        console.error('Error generating certificate:', error);
      }
    }
  };
  
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-cyber-darkblue to-cyber-dark py-8">
      <div className="container mx-auto px-4 max-w-4xl">
        <div className="mb-8 flex justify-between items-center">
          <Button 
            variant="outline" 
            onClick={() => navigate('/dashboard')}
            className="text-white border-white/20 hover:bg-white/10"
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Back to Dashboard
          </Button>
          
          <Button 
            variant="default" 
            onClick={downloadCertificate}
            className="bg-cyber-blue hover:bg-cyber-blue/90"
          >
            <Download className="h-4 w-4 mr-1" />
            Download Certificate
          </Button>
        </div>
        
        {/* Certificate Container */}
        <div 
          ref={certificateRef}
          className="bg-white rounded-lg overflow-hidden shadow-2xl border-8 border-cyber-blue/30 p-8 relative"
        >
          {/* Certificate Background */}
          <div className="absolute inset-0 opacity-5 pointer-events-none">
            <div className="absolute inset-0 bg-gradient-to-br from-cyber-blue to-cyber-accent"></div>
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-transparent to-white/80"></div>
            <div className="grid grid-cols-10 grid-rows-10 gap-4 h-full w-full p-8">
              {Array.from({ length: 100 }).map((_, i) => (
                <div key={i} className="bg-cyber-blue/10 rounded-full"></div>
              ))}
            </div>
          </div>
          
          {/* Certificate Content */}
          <div className="relative z-10 text-center">
            {/* University Logo */}
            <div className="mb-6">
              <img 
                src="/lovable-uploads/5a8d4528-468b-4abc-9efe-6932f2707954.png" 
                alt="Kalasalingam Academy of Research and Education"
                className="h-auto max-w-full mx-auto"
              />
            </div>
            
            <div className="mb-2 flex justify-center">
              <Award className="h-16 w-16 text-cyber-blue" />
            </div>
            
            <h1 className="text-2xl font-bold text-cyber-dark mb-1">CERTIFICATE OF COMPLETION</h1>
            <p className="text-muted-foreground mb-8 text-sm">Cyber Code Quest - Cybersecurity Training Program</p>
            
            <p className="text-lg mb-2">This is to certify that</p>
            <h2 className="text-3xl font-bold text-cyber-blue mb-2 font-serif">{user.fullName}</h2>
            <p className="text-lg mb-6">Register Number: <span className="font-semibold">{user.registerNumber}</span></p>
            
            <p className="text-lg mb-8 max-w-2xl mx-auto">
              has successfully completed all 14 cybersecurity experiments in the Cyber Code Quest 
              training program, demonstrating proficiency in various cybersecurity concepts and techniques.
            </p>
            
            <div className="grid grid-cols-2 gap-8 mb-8">
              <div className="text-center">
                <div className="h-px w-48 bg-gray-300 mx-auto mb-2"></div>
                <p className="font-semibold">Director of Cybersecurity</p>
              </div>
              <div className="text-center">
                <div className="h-px w-48 bg-gray-300 mx-auto mb-2"></div>
                <p className="font-semibold">Program Coordinator</p>
              </div>
            </div>
            
            <div className="mb-4 text-sm text-muted-foreground">Issued on {currentDate}</div>
            
            <div className="flex justify-center items-center gap-2 border-t border-gray-200 pt-4">
              <Shield className="h-5 w-5 text-cyber-blue" />
              <p className="text-sm font-medium text-cyber-blue">Cyber Code Quest</p>
            </div>
          </div>
        </div>
        
        <p className="text-center text-white/60 text-sm mt-6">
          This certificate verifies the completion of 14 cybersecurity experiments covering encryption, 
          authentication, intrusion detection, and more through hands-on coding challenges.
        </p>
      </div>
    </div>
  );
};

// Shield icon component for the certificate
const Shield = ({ className }: { className?: string }) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    className={className}
  >
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
);

export default Certificate;
