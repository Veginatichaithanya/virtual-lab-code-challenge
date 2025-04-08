
import { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/ui/use-toast";
import { useUser } from '@/context/UserContext';
import { LockKeyhole, ShieldCheck } from 'lucide-react';

const RegistrationForm = () => {
  const [fullName, setFullName] = useState('');
  const [registerNumber, setRegisterNumber] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { registerUser } = useUser();
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!fullName || !registerNumber) {
      toast({
        title: "Error",
        description: "Please fill in all the fields.",
        variant: "destructive",
      });
      return;
    }

    setIsSubmitting(true);

    try {
      // In a real app, we would send this data to Supabase here
      // For now, we'll just update our local state
      registerUser(fullName, registerNumber);
      
      toast({
        title: "Registration Successful",
        description: "You're now ready to start the challenges!",
      });
    } catch (error) {
      toast({
        title: "Registration Failed",
        description: "Please try again later.",
        variant: "destructive",
      });
      console.error("Registration error:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Card className="w-full max-w-md mx-auto border border-cyber-blue/20 bg-gradient-to-br from-cyber-dark to-cyber-darkblue shadow-lg">
      <CardHeader className="space-y-1">
        <div className="flex justify-center mb-4">
          <div className="bg-cyber-blue/10 p-3 rounded-full">
            <ShieldCheck className="h-10 w-10 text-cyber-blue" />
          </div>
        </div>
        <CardTitle className="text-2xl font-bold text-center text-white">Register for Cyber Code Quest</CardTitle>
        <CardDescription className="text-center text-gray-300">
          Enter your details to start the cybersecurity challenges
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="fullName" className="text-white">Full Name</Label>
            <div className="relative">
              <Input
                id="fullName"
                type="text"
                placeholder="John Doe"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="pl-10 bg-cyber-dark/80 border-cyber-blue/30 text-white placeholder:text-gray-500"
                required
              />
              <LockKeyhole className="absolute left-3 top-2.5 h-5 w-5 text-cyber-blue/70" />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="registerNumber" className="text-white">Register Number</Label>
            <div className="relative">
              <Input
                id="registerNumber"
                type="text"
                placeholder="e.g., CS12345"
                value={registerNumber}
                onChange={(e) => setRegisterNumber(e.target.value)}
                className="pl-10 bg-cyber-dark/80 border-cyber-blue/30 text-white placeholder:text-gray-500"
                required
              />
              <ShieldCheck className="absolute left-3 top-2.5 h-5 w-5 text-cyber-blue/70" />
            </div>
          </div>
          <Button 
            type="submit" 
            className="w-full bg-cyber-blue hover:bg-cyber-blue/80 text-white"
            disabled={isSubmitting}
          >
            {isSubmitting ? "Registering..." : "Register & Begin Challenges"}
          </Button>
        </form>
      </CardContent>
      <CardFooter className="flex justify-center border-t border-cyber-blue/20 pt-4">
        <p className="text-xs text-gray-400 text-center">
          Your details will be used to generate your completion certificate
          after finishing all the cybersecurity challenges.
        </p>
      </CardFooter>
    </Card>
  );
};

export default RegistrationForm;
