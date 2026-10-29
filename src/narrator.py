import os
from dotenv import load_dotenv
from elevenlabs.client import ElevenLabs

load_dotenv()

class GhostNarrator:
    """
    Synthesizes spoken incident briefings, voice séance replies, and exorcism sound effects
    using ElevenLabs TTS, STT (scribe_v1), and Text-to-Sound-Effects APIs.
    """
    def __init__(self):
        self.api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
        # Authoritative Commander Voice for Tab 1 Incident Briefings
        self.voice_id = os.getenv("ELEVENLABS_VOICE_ID", "JBFqnCBsd6RMkjVDRZzb").strip()
        # Eerie/Hoarse Voice (Callum) for Tab 2 Haunted Process Séance Replies
        self.ghost_voice_id = os.getenv("ELEVENLABS_GHOST_VOICE_ID", "N2lVS1w4EtoT3dr4eOWO").strip()
        self.cache_dir = "audio_cache"
        os.makedirs(self.cache_dir, exist_ok=True)

    def generate_briefing_audio(self, autopsy_dict: dict) -> str:
        """
        Generates an MP3 audio briefing for a given GhostAutopsy dict and returns the file path.
        """
        resource_id = autopsy_dict.get("resource_id", "unknown")
        safe_id = "".join(c if c.isalnum() else "_" for c in str(resource_id))
        output_path = os.path.join(self.cache_dir, f"alert_{safe_id}.mp3")

        # Return cached MP3 if already generated (saves API credits!)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
            print(f"🔊 Using cached ElevenLabs audio briefing: {output_path}")
            return output_path

        if not self.api_key or "your_elevenlabs" in self.api_key:
            print("⚠️ ElevenLabs API key not configured properly in .env")
            return None

        script = (
            f"Phantom Ops Critical Alert for resource {resource_id}. "
            f"{autopsy_dict.get('incident_title')}. "
            f"{autopsy_dict.get('root_cause_autopsy')} "
            f"Estimated financial drain is {autopsy_dict.get('monthly_waste_usd')} dollars per month. "
            f"Awaiting human authorization via Auth0 to execute exorcism."
        )

        try:
            print(f"🎙️ Generating ElevenLabs voice briefing for {resource_id}...")
            client = ElevenLabs(api_key=self.api_key)
            audio_generator = client.text_to_speech.convert(
                voice_id=self.voice_id,
                output_format="mp3_44100_128",
                text=script,
                model_id="eleven_multilingual_v2"
            )
            
            with open(output_path, "wb") as f:
                for chunk in audio_generator:
                    if chunk:
                        f.write(chunk)
                        
            print(f"✅ Audio briefing saved to: {output_path}")
            return output_path
        except Exception as e:
            print(f"⚠️ ElevenLabs TTS error: {e}")
            return None

    def transcribe_seance_question(self, audio_bytes: bytes) -> str:
        """
        Uses ElevenLabs Speech-to-Text (scribe_v1) to transcribe the user's spoken question
        for the local Gemma 2 model.
        """
        if not self.api_key:
            return "Why are you consuming so much memory and CPU?"
        try:
            import io
            client = ElevenLabs(api_key=self.api_key)
            audio_Bio = io.BytesIO(audio_bytes)
            audio_Bio.name = "seance_question.wav"
            transcription = client.speech_to_text.convert(
                file=audio_Bio,
                model_id="scribe_v1"
            )
            return getattr(transcription, "text", str(transcription)).strip()
        except Exception as e:
            print(f"⚠️ ElevenLabs STT fallback: {e}")
            return "Why are you haunting my system and leaking memory?"

    def synthesize_seance_reply(self, resource_id: str, reply_text: str) -> str:
        """
        Synthesizes the ghost process's spoken séance answer via ElevenLabs TTS using a distinct eerie voice.
        """
        safe_id = "".join(c if c.isalnum() else "_" for c in str(resource_id))
        output_path = os.path.join(self.cache_dir, f"seance_{safe_id}.mp3")
        if not self.api_key:
            return None
        try:
            client = ElevenLabs(api_key=self.api_key)
            audio_generator = client.text_to_speech.convert(
                voice_id=self.ghost_voice_id,
                output_format="mp3_44100_128",
                text=reply_text,
                model_id="eleven_multilingual_v2"
            )
            with open(output_path, "wb") as f:
                for chunk in audio_generator:
                    if chunk:
                        f.write(chunk)
            return output_path
        except Exception as e:
            print(f"⚠️ ElevenLabs Séance TTS error: {e}")
            return None

    def generate_exorcism_sfx(self) -> str:
        """
        Uses ElevenLabs Text-to-Sound-Effects API to synthesize a cybernetic power-down sound when a PID dies.
        """
        sfx_path = os.path.join(self.cache_dir, "exorcism_sfx.mp3")
        if os.path.exists(sfx_path) and os.path.getsize(sfx_path) > 1000:
            return sfx_path
        if not self.api_key:
            return None
        try:
            client = ElevenLabs(api_key=self.api_key)
            sfx_gen = client.text_to_sound_effects.convert(
                text="Sci-fi server rack power down with a ghostly digital whoosh and electrical discharge",
                duration_seconds=3.0
            )
            with open(sfx_path, "wb") as f:
                for chunk in sfx_gen:
                    if chunk:
                        f.write(chunk)
            return sfx_path
        except Exception as e:
            print(f"⚠️ ElevenLabs SFX error: {e}")
            return None

if __name__ == "__main__":
    narrator = GhostNarrator()
    sample_autopsy = {
        "resource_id": "inst-10525",
        "incident_title": "Staging Dev Instance: Phantom-Level Anomaly Detected!",
        "root_cause_autopsy": "The instance shows near-constant CPU utilization at 99.9% with zero active connections.",
        "monthly_waste_usd": 620.5
    }
    narrator.generate_briefing_audio(sample_autopsy)
    