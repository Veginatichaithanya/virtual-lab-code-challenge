
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Server, AlertTriangle, RefreshCw, Key, Database, Network } from 'lucide-react';
import RegistrationForm from '@/components/RegistrationForm';
import { useUser } from '@/context/UserContext';

const Index = () => {
  const { user } = useUser();
  const navigate = useNavigate();

  // If user is already registered, redirect to dashboard
  useEffect(() => {
    if (user.isRegistered) {
      navigate('/dashboard');
    }
  }, [user.isRegistered, navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-darkblue to-cyber-dark">
      <div className="container mx-auto px-4 py-12">
        <header className="mb-12 text-center">
          <div className="flex justify-center mb-4">
            <div className="bg-cyber-blue/10 p-3 rounded-full">
              <Shield className="h-12 w-12 text-cyber-blue" />
            </div>
          </div>
          <h1 className="text-4xl font-bold text-white mb-3">VIRTUAL LAB CODE CHALLENGE</h1>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            Master essential cybersecurity concepts through 14 interactive coding experiments
          </p>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-16 mb-16">
          <div className="space-y-8">
            <div className="text-white">
              <h2 className="text-2xl font-bold mb-4">Start Your Cybersecurity Journey</h2>
              <p className="text-gray-300 mb-6">
                The VIRTUAL LAB CODE CHALLENGE platform provides hands-on experience with real-world cybersecurity 
                techniques through interactive coding challenges. From basic encryption algorithms to 
                advanced security implementations, you'll build practical skills essential for today's 
                digital security landscape.
              </p>
              
              <div className="grid grid-cols-2 gap-4">
                <FeatureItem 
                  icon={Lock} 
                  title="Encryption Techniques" 
                  description="Learn various encryption methods including Caesar cipher, AES, and RSA"
                />
                <FeatureItem 
                  icon={Key} 
                  title="Authentication" 
                  description="Implement message authentication codes and digital signatures"
                />
                <FeatureItem 
                  icon={AlertTriangle} 
                  title="Intrusion Detection" 
                  description="Practice configuring and using network security monitoring tools"
                />
                <FeatureItem 
                  icon={Database} 
                  title="Database Security" 
                  description="Secure databases with proper access control and encryption"
                />
                <FeatureItem 
                  icon={RefreshCw} 
                  title="Real-time Feedback" 
                  description="Get instant feedback on your code with detailed error reporting"
                />
                <FeatureItem 
                  icon={Server} 
                  title="Malware Analysis" 
                  description="Analyze and detect malicious software in a safe environment"
                />
              </div>
            </div>
          </div>
          
          <div>
            <RegistrationForm />
          </div>
        </div>
        
        <div className="bg-white/5 rounded-lg p-6 border border-white/10 max-w-4xl mx-auto">
          <h3 className="text-xl font-bold text-white mb-4">What You'll Learn</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {experiments.map((exp, index) => (
              <div key={index} className="flex gap-3 items-start">
                <div className="bg-cyber-blue/10 p-1.5 rounded-full mt-0.5">
                  <Network className="h-4 w-4 text-cyber-blue" />
                </div>
                <div>
                  <h4 className="font-semibold text-white">{exp.title}</h4>
                  <p className="text-sm text-gray-400">{exp.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

const FeatureItem = ({ icon: Icon, title, description }: { icon: any; title: string; description: string }) => (
  <div className="flex flex-col gap-2">
    <div className="flex items-center gap-2">
      <div className="bg-cyber-blue/10 p-1.5 rounded-full">
        <Icon className="h-4 w-4 text-cyber-blue" />
      </div>
      <h3 className="font-semibold">{title}</h3>
    </div>
    <p className="text-sm text-gray-400">{description}</p>
  </div>
);

const experiments = [
  { title: "Caesar Cipher", description: "Basic character shifting for encryption" },
  { title: "Monoalphabetic Cipher", description: "Static mapping substitution techniques" },
  { title: "Message Authentication", description: "Ensure message integrity with authentication tags" },
  { title: "Data Encryption Standard", description: "Classic symmetric block ciphers" },
  { title: "Advanced Encryption Standard", description: "Modern encryption for secure data" },
  { title: "Asymmetric Key Encryption", description: "Public-private key systems like RSA" },
  { title: "Secure Key Exchange", description: "Protocols like Diffie-Hellman" },
  { title: "Digital Signatures", description: "Authenticate data with cryptographic signatures" },
];

export default Index;
